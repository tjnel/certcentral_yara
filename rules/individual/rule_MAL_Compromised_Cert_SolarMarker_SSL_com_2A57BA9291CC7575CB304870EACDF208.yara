import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_2A57BA9291CC7575CB304870EACDF208 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-09"
      version             = "1.0"

      hash                = "f88a27309d2915e04cd8ccac850db250f214ade9ce0fe38029f0214283ebb5c4"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"локкерс\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2a:57:ba:92:91:cc:75:75:cb:30:48:70:ea:cd:f2:08"
      cert_thumbprint     = "3409E59F9197D8FD48470533D4FC517BAA3DD212"
      cert_valid_from     = "2023-11-09"
      cert_valid_to       = "2024-11-08"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro Raion"
      email               = "???"
      rdn_serial_number   = "45321657"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2a:57:ba:92:91:cc:75:75:cb:30:48:70:ea:cd:f2:08"
      )
}
