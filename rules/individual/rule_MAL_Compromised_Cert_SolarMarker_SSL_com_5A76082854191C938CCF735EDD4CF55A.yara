import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_5A76082854191C938CCF735EDD4CF55A {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-10-25"
      version             = "1.0"

      hash                = "af1f2b516ede83cf2699ba54113ce7a7d81d17040588746a19a1fa2ea41175d6"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Softindex Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5a:76:08:28:54:19:1c:93:8c:cf:73:5e:dd:4c:f5:5a"
      cert_thumbprint     = "DFA83E459316D496FDB1BCD7E78A15D489A4F1C6"
      cert_valid_from     = "2022-10-25"
      cert_valid_to       = "2023-09-22"

      country             = "GB"
      state               = "???"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "14080111"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5a:76:08:28:54:19:1c:93:8c:cf:73:5e:dd:4c:f5:5a"
      )
}
