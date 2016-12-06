# -*- coding: utf-8 -*-
#
# simple zabbix_sender utility, based on gist by 'miyucy'
#   https://gist.github.com/1170577
#
require 'socket'
require 'json'
require 'openssl'

module Puppet::Util::Zabbix
  class Sender
    attr_reader :serv, :port, :items, :tls_connect, :tls_ca_file, :tls_cert_file, :tls_key_file

    # static method exaple usage:
    # Puppet::Util::Zabbix::Sender.send 'host', 'zabbix_host', 10051 do
    #   add_item 'key', 'value'
    # end
    def self.send(host, serv = 'localhost', port = 10051, &blk)
      s = new serv, port
      s.instance_eval(&blk)
      s.send! host
    end

    def initialize(serv = 'localhost', port = 10051, tls_connect = false, tls_ca_file = '', tls_cert_file = '', tls_key_file = '')
      @serv, @port, @tls_connect, @tls_ca_file, @tls_cert_file, @tls_key_file = serv, port, tls_connect, tls_ca_file, tls_cert_file, tls_key_file
      @items = {}
    end

    def add_item(key, value)
      @items[key] = value
    end

    def send!(host)
      return if @items.empty?
      begin
        if @tls_connect
          tls_connect @items.map { |key, value|
            { :host => host.to_s, :key => key.to_s, :value => value.to_s }
          }
        else
          connect @items.map { |key, value|
            { :host => host.to_s, :key => key.to_s, :value => value.to_s }
          }
        end
      ensure
        @items = {}
      end
    end

    protected

    def tls_connect(data)
      socket = nil
      ssl_socket = nil
      begin
        socket = TCPSocket.new @serv, @port
        ssl_context = OpenSSL::SSL::SSLContext.new()
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
        ssl_context.ca_file = @tls_ca_file
        ssl_context.cert = OpenSSL::X509::Certificate.new(File.open(@tls_cert_file))
        ssl_context.key = OpenSSL::PKey::RSA.new(File.open(@tls_key_file))
        ssl_context.ssl_version = :SSLv23
        ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
        ssl_socket.sync_close = true
        ssl_socket.connect
        ssl_socket.write rawdata(data)
        JSON.parse ssl_socket.read[13 .. -1]
      ensure
        ssl_socket.close if ssl_socket
        #socket.close if sock
      end
    end

    def connect(data)
      sock = nil
      begin
        sock = TCPSocket.new @serv, @port
        sock.write rawdata(data)
        JSON.parse sock.read[13 .. -1]
      ensure
        sock.close if sock
      end
    end

    def rawdata(data)
      data = [data] unless data.instance_of? Array
      baggage = {
        :request => 'sender data',
        :data    => data,
      }.to_json

      "ZBXD\1" + [baggage.bytesize].pack("i") + "\0\0\0\0" + baggage
    end

  end
end
