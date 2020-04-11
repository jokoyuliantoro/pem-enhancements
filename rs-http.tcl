# Rapid Signature - HTTP
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
      set cmd "if { \$srv_ptr_name [lindex $c 1] \"[lindex $c 2]\" } { CLASSIFY::application set [lindex $ptre 1] }"
      catch { eval $cmd }
    }
    # Custom classification on PTR - End

    # Custom action on PTR - Start
    foreach ptracte [class get _dpi-action-on-ptr ] {
      set c [ split [lindex $ptracte 0] \; ]
      set cmd "if { \$srv_ptr_name [lindex $c 1] \"[lindex $c 2]\" } { set action [lindex $ptracte 1] }"
      catch { eval $cmd }
    }
    unset -nocomplain c cmd ptracte ptraction
    # Custom action on PTR - End
  }

  if { $action eq "Block" } {
    drop
    return
  } elseif { $action eq "Rate_Shape" } {
    BWC::policy attach $static::ebwc_rate_shape [IP::client_addr]
  }

  ### Connection Debugging - Start ###
  set l3l4 "[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]"
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
      HSL::send $hsl "HTTP\$\$0\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
    }
  }
  ### Connection Debugging - End ###  
}

when HTTP_REQUEST {
  set httpinfo ""
  foreach hdr [HTTP::header names] {
    set hdrv [HTTP::header value $hdr]
    if { $httpinfo ne "" } { append httpinfo "###"}
    append httpinfo "$hdr:$hdrv"
  }
  
  if { [HTTP::host] ne "" } {
    # Custom action on HTTP-Host - Start
    foreach ptracte [class get _dpi-action-on-http-host ] {
      set c [ split [lindex $ptracte 0] \; ]
      set cmd "if { [HTTP::host] [lindex $c 1] \"[lindex $c 2]\" } { set action [lindex $ptracte 1] }"
      catch { eval $cmd }
    }
    unset -nocomplain c cmd ptracte ptraction
    # Custom action on HTTP-Host - End
  }
  if { $action eq "Block" } {
    drop
    return
  } elseif { $action eq "Rate_Shape" } {
    BWC::policy attach $static::ebwc_rate_shape [IP::client_addr]
  }
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
  HSL::send $hsl "HTTP\$\$0\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
  ### Connnection Debugging - End ###
}

when HTTP_RESPONSE {
  set httpstatus [HTTP::status]
  set httpsinfo ""
  foreach hdr [HTTP::header names] {
    set hdrv [HTTP::header value $hdr]
    if { $httpsinfo ne "" } { append httpsinfo "###"}
    append httpsinfo "$hdr:$hdrv"
  }
  set curpkt [IP::stats]
  set dpi [expr {[lindex $curpkt 0]-[lindex $lstpkt 0]}]
  set dpo [expr {[lindex $curpkt 1]-[lindex $lstpkt 1]}]
  set dbi [expr {[lindex $curpkt 2]-[lindex $lstpkt 2]}]
  set dbo [expr {[lindex $curpkt 3]-[lindex $lstpkt 3]}]
  set ipstat "$dpi\$\$$dpo\$\$$dbi\$\$$dbo\$\$[lindex $curpkt 4]"
  HSL::send $hsl "HTTP\$\$0\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$$l3l4\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
}

when CLIENT_CLOSED {
  ### Connnection Debugging - Start ###
  set curpkt [IP::stats]
  set dpi [expr {[lindex $curpkt 0]-[lindex $lstpkt 0]}]
  set dpo [expr {[lindex $curpkt 1]-[lindex $lstpkt 1]}]
  set dbi [expr {[lindex $curpkt 2]-[lindex $lstpkt 2]}]
  set dbo [expr {[lindex $curpkt 3]-[lindex $lstpkt 3]}]
  set ipstat "$dpi\$\$$dpo\$\$$dbi\$\$$dbo\$\$[lindex $curpkt 4]"
  HSL::send $hsl "HTTP\$\$1\$\$$action\$\$$tccat\$\$$tcapp\$\$$tcres\$\$$srv_ptr_name\$\$$asorigin\$\$[IP::client_addr]\$\$[TCP::client_port]\$\$[IP::local_addr]\$\$[TCP::local_port]\$\$$ipstat\$\$$sni\$\$$sni_lookup\$\$$cipher\$\$$httpinfo\$\$$httpstatus\$\$$httpsinfo\$\$$subsid\$\$$rat\$\$$nas\$\$$imei\$\$$towerid\$\$$callingsid\$\$$calledsid"
  ### Connnection Debugging - End ###
}

