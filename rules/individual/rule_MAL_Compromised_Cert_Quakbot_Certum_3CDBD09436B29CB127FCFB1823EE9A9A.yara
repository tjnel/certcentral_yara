import "pe"

rule MAL_Compromised_Cert_Quakbot_Certum_3CDBD09436B29CB127FCFB1823EE9A9A {
   meta:
      description         = "Detects Quakbot with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-05"
      version             = "1.0"

      hash                = "de095ea31816e724d6ec46f703b096e893efec5bcba9d018c52820e22d4fbd45"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

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
