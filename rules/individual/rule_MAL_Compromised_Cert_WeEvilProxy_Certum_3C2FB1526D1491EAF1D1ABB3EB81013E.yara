import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_Certum_3C2FB1526D1491EAF1D1ABB3EB81013E {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-11"
      version             = "1.0"

      hash                = "038f21a41ff6cb0bdcd47323e4c612a8733d8953a5b059fa1168c65185bba4f9"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "Optyprism Limited"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "3c:2f:b1:52:6d:14:91:ea:f1:d1:ab:b3:eb:81:01:3e"
      cert_thumbprint     = "7BB22A166D2B74CF6B2682AAD92C934705C07978"
      cert_valid_from     = "2024-06-11"
      cert_valid_to       = "2025-06-11"

      country             = "GB"
      state               = "???"
      locality            = "LONDON"
      email               = "???"
      rdn_serial_number   = "12843522"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "3c:2f:b1:52:6d:14:91:ea:f1:d1:ab:b3:eb:81:01:3e"
      )
}
