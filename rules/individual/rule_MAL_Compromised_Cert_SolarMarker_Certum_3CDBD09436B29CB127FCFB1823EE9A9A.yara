import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_3CDBD09436B29CB127FCFB1823EE9A9A {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-05"
      version             = "1.0"

      hash                = "28b41fbae3fec855c2f4779dde8d4e990d3e5ceede80a89bcf420a59459d84b8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "FORMICA Solution a.s."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "3c:db:d0:94:36:b2:9c:b1:27:fc:fb:18:23:ee:9a:9a"
      cert_thumbprint     = "CD868D85C7FA7A55C568ECD4B3F835D9D0486266"
      cert_valid_from     = "2021-02-05"
      cert_valid_to       = "2022-02-05"

      country             = "CZ"
      state               = "???"
      locality            = "Čestlice"
      email               = "???"
      rdn_serial_number   = "04668855"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "3c:db:d0:94:36:b2:9c:b1:27:fc:fb:18:23:ee:9a:9a"
      )
}
