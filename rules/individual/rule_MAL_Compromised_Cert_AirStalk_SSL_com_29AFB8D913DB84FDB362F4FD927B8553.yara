import "pe"

rule MAL_Compromised_Cert_AirStalk_SSL_com_29AFB8D913DB84FDB362F4FD927B8553 {
   meta:
      description         = "Detects AirStalk with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-28"
      version             = "1.0"

      hash                = "0c444624af1c9cce6532a6f88786840ebce6ed3df9ed570ac75e07e30b0c0bde"
      malware             = "AirStalk"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Aoteng Industrial Automation (Langfang) Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "29:af:b8:d9:13:db:84:fd:b3:62:f4:fd:92:7b:85:53"
      cert_thumbprint     = "2A4AECD2A7451A60AF367A5E44294AE7E185842A"
      cert_valid_from     = "2024-06-28"
      cert_valid_to       = "2025-06-28"

      country             = "CN"
      state               = "Hebei"
      locality            = "Langfang"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "29:af:b8:d9:13:db:84:fd:b3:62:f4:fd:92:7b:85:53"
      )
}
