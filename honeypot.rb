
require 'socket'

module Honeypot
  VERSION = '0.1.0'

  class Response
    FLAGS = %w{suspicious harvester comment_spammer}

    SEARCH_ENGINE_IDS = %w{
      google
    }

    def initialize(addr, sock_addr)
      @h = {
        :raw    => sock_addr,
        :age    => addr[1],
        :threat => addr[2],
        :flags  => addr[3],
      }
    end

    def search_engine?
      !@h[:flags]
    end

    def search_engine
      nil unless search_engine?
    end

    FLAGS.each_with_index do |flag, i|
      self.const_set("FLAG_#{flag}".upcase, 1 << i)

      class_eval %{
        def #{flag}?
          !!(flags & (1 << #{i}))
        end
      }
    end

    def flags
      @h[:flags]
    end

    def age
      @h[:age]
    end

    def threat
      @h[:threat]
    end
  end

  class Honeypot
    DEFAULTS = {
      # root to append to dns requests
      :root       => 'dnsbl.httpbl.org',

      # debugging enabled?
      :debug      => false,

      # threshold for ok? threat check
      :ok_threat  => 128,

      # threshold for ok? age check
      :ok_age     => 128,
    }

    def initialize(api_key = nil, opt = {})
      @opt = DEFAULTS.merge(opt || {})
      @api_key = api_key || ENV['HONEYPOT_RUBY_API_KEY']
    end

    def check(ip)
      host = build_query(ip)
      $stderr.puts "#{ip} => #{host}" if @opt[:debug]
      do_query(host)
    end

    def [](ip)
      check(ip)
    end

    def ok?(ip)
      r = check(ip)
      !r || ((!@opt[:ok_age] || r.age > @opt[:ok_age]) &&
             (!@opt[:ok_threat] || r.threat < @opt[:ok_threat]))
    end

    private

    def flip_ip(ip)
      ip.split(/\./).reverse.join('.')
    end

    def is_ip?(str)
      str.split(/\./).all? { |v| v =~ /^\d+$/ }
    end

    def lookup_host(host)
      r = Socket.gethostbyname(host)
      r[3].unpack('c4').join('.')
    end 

    def build_query(ip)
      ip = lookup_host(ip) unless is_ip?(ip)
      ip = flip_ip(ip)
      "#@api_key.#{ip}.#{@opt[:root]}"
    end

    def do_query(host)
      r = Socket.gethostbyname(host) rescue nil
      return nil unless r

      a = r[3].unpack('c4')
      return nil if a[0] != 127

      Response.new(a, r)
    end
  end

  def self.new(api_key = nil, opt = {})
    Honeypot.new(api_key, opt)
  end
end
