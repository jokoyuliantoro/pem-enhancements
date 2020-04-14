# Rapid Siganture iRule - TCP/SSL
#
when RULE_INIT {
  if { ![info exists static::ratmap] } {
    array set static::nat {
      0 Reserved
      1 UTRAN
      2 GERAN
      3 WLAN
      4 GAN
      5 HSPAEvo
      6 EUTRAN
      7 Virtual
    }
  }
  if { ![info exists static::eresolver] } {
    set static::eresolver "8.8.8.8"
  }
  if { ![info exists static::ebwc_rate_shape] } {
    set static::ebwc_rate_shape "bwc_5k"
  }
}

when CLIENT_ACCEPTED {
  ### PEM Session - Start ###
  if { [PEM::session info [IP::client_addr] state] ne "provisioned" } {
    set pol_name [class match -value "session-policies" equals _dg-dpi-config]
    if { $pol_name ne "" } {
      set cmd2exec "PEM::session config policy referential set \"[IP::client_addr]\" $pol_name"
      eval $cmd2exec    
    }
    PEM::session info [IP::client_addr] state provisioned
  }
  ### PEM Session - End ###

  ### Init - Start ###
  set tccat "No_Category"
  set tcapp "No_AppName"
  set tcres "No_DPI_Res"
  set httpinfo "No_HTTP_Info"
  set action "Allow"
  set sni "No_SNI"
  set sni_lookup "No_SNI_Lookup"
  set cipher "No_Cipher"
  set httpinfo "Host:N/A###User-Agent:N/A###ReqHeader1:N/A###ReqHeader2:N/A###ReqHeader3:N/A"
  set httpsinfo "Server:N/A###Content-Type:N/A###ResHeader1:N/A###ResHeader2:N/A###ResHeader3:N/A"
  set httpstatus "No_Status"
  set mobileinfo [table lookup mobinfo-[IP::client_addr]]
  if { $mobileinfo ne "" } {
    set subsid [lindex $mobileinfo 0]
    set rat $static::ratmap([lindex $mobileinfo 1])
    set nas [lindex $mobileinfo 2]
    set imei [lindex $mobileinfo 3]
    set towerid [lindex $mobileinfo 4]
    set callingsid [lindex $mobileinfo 5]
    set calledsid [lindex $mobileinfo 6]
  } else {
    set subsid "Missing"
    set rat "Missing"
    set nas "Missing"
    set imei "Missing"
    set towerid "Missing"
    set callingsid "Missing"
    set calledsid "Missing"
  }
  set proto "TCP"
  ### Init - End ###

  ### Server PTR Name - Start ###
  set srv_ptr_name [ table lookup "ptr-[IP::local_addr]" ]
  if { $srv_ptr_name eq "" } {
    set res [RESOLV::lookup @$static::eresolver -ptr [IP::local_addr]]
    if { $res ne "" } {
      set srv_ptr_name $res
      table set "ptr-[IP::local_addr]" $res 300
    } else {
      set srv_ptr_name "No_PTR"
    }
  }
  unset -nocomplain res
  ### Server PTR Name - End ###
  if { $srv_ptr_name ne "No_PTR" } {
    # Custom classification on PTR - Start
    foreach ptre [class get _dpi-classify-on-ptr ] {
      set c [ split [lindex $ptre 0] \; ]
      set a [ lindex $ptre 1 ]
      set cmd "if { \$srv_ptr_name [lindex $c 1] \"[lindex $c 2]\" } { CLASSIFY::application set $a }"
      catch { eval $cmd }
    }
    # Custom classification on PTR - End

    # Custom action on PTR - Start
    foreach ptracte [class get _dpi-action-on-ptr ] {
      set c [ split [lindex $ptracte 0] \; ]
      set a [ lindex $ptracte 1 ]
      set cmd "if { \$srv_ptr_name [lindex $c 1] \"[lindex $c 2]\" } { set action $a }"
      catch { eval $cmd }
    }
    unset -nocomplain a c cmd ptracte ptraction
    # Custom action on PTR - End
  }

  if { $action eq "Block" } {
    drop
    return
  } elseif { $action eq "Rate_Shape" } {
    BWC::policy attach $static::ebwc_rate_shape [IP::client_addr]
  }

  ### Connection Debugging - Start ###
  set hsl [ HSL::open -proto UDP -pool hsl-elk-2 ]
  set asorigin [class match -value [IP::local_addr] equals _dpi-as-origin]
  if { $asorigin ne "" } {
  } else { 
    set asorigin "No_AS_Rcvd"
  } 
  set lstpkt [IP::stats]
  after 5000 -periodic {
    set curpkt [IP::stats]
    if { "[lindex $lstpkt 0][lindex $lstpkt 1]" ne "[lindex $curpkt 0][lindex $curpkt 1]" } {
      set dpi [expr {[lindex $curpkt 0]-[lindex $lstpkt 0]}]
      set dpo [expr {[lindex $curpkt 1]-[lindex $lstpkt 1]}]
      set dbi [expr {[lindex $curpkt 2]-[lindex $lstpkt 2]}]
      set dbo [expr {[lindex $curpkt 3]-[lindex $lstpkt 3]}]
      set ipstat "$dpi\$\$$dpo\$\$$dbi\$\$$dbo\$\$[lindex $curpkt 4]"
      set lstpkt $curpkt
      HSL::send $hsl "$proto\$\$0\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
    }
  }
  ### Connection Debugging - End ###

  if { [TCP::local_port] eq 443 } {
    set sni_parsed 0
  }

  TCP::collect
}

when CLIENT_DATA {
  ### SNI Parser - Start ###
  if { [TCP::local_port] eq 443 } {
    if { $sni_parsed eq 0 } {
      set proto "SSL"
      # Based on k.stewart iRule
      set payload [TCP::payload 16389]
      set payloadlen [TCP::payload length]
      if { [binary scan $payload cH4Scx3H4x32c tls_record_content_type tls_version tls_recordlen tls_handshake_action tls_handshake_version tls_handshake_sessidlen] == 6 && \
        ($tls_record_content_type == 22) && \
        ([string match {030[1-3]} $tls_version]) && \
        ($tls_handshake_action == 1) && \
        ($payloadlen == $tls_recordlen+5)} { 
        # store in a variable the handshake version
        set tls_handshake_prefered_version $tls_handshake_version
        # skip past the session id
        set record_offset [expr {44 + $tls_handshake_sessidlen}]
        # skip past the cipher list
        binary scan $payload @${record_offset}S tls_ciphlen
        set record_offset [expr {$record_offset + 2 + $tls_ciphlen}]
        # skip past the compression list
        binary scan $payload @${record_offset}c tls_complen
        set record_offset [expr {$record_offset + 1 + $tls_complen}]
        # check for the existence of ssl extensions
        if { ($payloadlen > $record_offset) } {
          # skip to the start of the first extension
          binary scan $payload @${record_offset}S tls_extension_length
          set record_offset [expr {$record_offset + 2}]
          # Check if extension length + offset equals payload length
          if {$record_offset + $tls_extension_length == $payloadlen} {
            # for each extension
            while { $record_offset < $payloadlen } {
              binary scan $payload @${record_offset}SS tls_extension_type tls_extension_record_length
              if { $tls_extension_type == 0 } {
                # if it's a servername extension read the servername
                # SNI record value start after extension type (2 bytes), extension record length (2 bytes), record type (2 bytes), record type (1 byte), record value length (2 bytes) = 9 bytes
                binary scan $payload @[expr {$record_offset + 9}]A[expr {$tls_extension_record_length - 5}] tls_servername
                set record_offset [expr {$record_offset + $tls_extension_record_length + 4}]                      
              } elseif { $tls_extension_type == 43 } {
                # if it's a supported_version extension (starting with TLS 1.3), extract supported version in a list
                binary scan $payload @[expr {${record_offset} + 4}]cS[expr {($tls_extension_record_length -1)/2}] tls_supported_versions_length tls_supported_versions
                set tls_handshake_prefered_version [list]
                foreach version $tls_supported_versions {
                  lappend tls_handshake_prefered_version [format %04X [expr { $version & 0xffff }] ]
                }
                set record_offset [expr {$record_offset + $tls_extension_record_length + 4}]
              } else {
                # skip over other extensions
                set record_offset [expr {$record_offset + $tls_extension_record_length + 4}]
              }
            }
          }
        }
      } elseif { [binary scan $payload cH4 ssl_record_content_type ssl_version] == 2 && \
        ($tls_record_content_type == 22) && \
        ($tls_version == 0300)} {
        # SSLv3 detected
        set tls_handshake_prefered_version "0300"
      } elseif { [binary scan $payload H2x1H2 ssl_version handshake_protocol_message] == 2 && \
        ($ssl_version == 80) && \
        ($handshake_protocol_message == 01)} {
        # SSLv2 detected
        set tls_handshake_prefered_version "0200"
      }
      unset -nocomplain payload payloadlen tls_record_content_type tls_recordlen tls_handshake_action tls_handshake_sessidlen record_offset tls_ciphlen tls_complen tls_extension_length tls_extension_type tls_extension_record_length tls_supported_versions_length tls_supported_versions
      set sni_parsed 1

      if { $tls_servername ne "" } {
        set sni $tls_servername
        set sni_lookup [ table lookup "a-$sni" ]
        if { $sni_lookup eq "" } {
          set res [RESOLV::lookup @$static::eresolver $sni]
          if { $res ne "" } {
            set sni_lookup $res
            table set "a-$sni" $res 300
          } else {
            set sni_lookup "No_SNI_Lookup"
          }
        }
        
        # Custom classification on SNI - Start
        foreach e [class get _dpi-classify-on-sni ] {
          set c [ split [lindex $e 0] \; ]
          set a [ lindex $e 1 ]
          set cmd "if { \$sni [lindex $c 1] \"[lindex $c 2]\" } { CLASSIFY::application set $a }"
          catch { eval $cmd }
        }
        # Custom classification on SNI - End
        # Custom action on SNI - Start
        foreach e [class get _dpi-action-on-sni ] {
          set c [ split [ lindex $e 0 ] \; ]
          set a [ lindex $e 1 ]
          set cmd "if { \$sni [lindex $c 1] \"[lindex $c 2]\" } { set action $a }"
          catch { eval $cmd }
        }
        unset -nocomplain a c cmd e
        if { $action eq "Block" } {
          drop
          return
        } elseif { $action eq "Rate_Shape" } {
          BWC::policy attach $static::ebwc_rate_shape [IP::client_addr]
        }
        # Custom action on SNI - End
      }
    }
  }
  ### SNI Parser - End ###

  TCP::release
  TCP::collect
}

when CLASSIFICATION_DETECTED {
  set tccat [CLASSIFICATION::category]
  set tcapp [CLASSIFICATION::app]
  set tcres [string map {" " /} [CLASSIFICATION::result]]

  # App to action
  set act [ class match -value $tcapp equals _dg-app-action ]
  if { $act ne "" } {
    set action $act    
  }

  ### Connnection Debugging - Start ###
  set lstpkt [IP::stats]
  set ipstat [string map {" " \$\$} [IP::stats] ]
  HSL::send $hsl "$proto\$\$0\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
  ### Connnection Debugging - End ###
}

when CLIENT_CLOSED {
  ### Connnection Debugging - Start ###
  set curpkt [IP::stats]
  set dpi [expr {[lindex $curpkt 0]-[lindex $lstpkt 0]}]
  set dpo [expr {[lindex $curpkt 1]-[lindex $lstpkt 1]}]
  set dbi [expr {[lindex $curpkt 2]-[lindex $lstpkt 2]}]
  set dbo [expr {[lindex $curpkt 3]-[lindex $lstpkt 3]}]
  set ipstat "$dpi\$\$$dpo\$\$$dbi\$\$$dbo\$\$[lindex $curpkt 4]"
  HSL::send $hsl "$proto\$\$1\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
  ### Connnection Debugging - End ###
}

