import "pe"

rule MAL_Compromised_Cert_Quakbot_SSL_com_03980D54388F052199A48939D5203C0C {
   meta:
      description         = "Detects Quakbot with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-14"
      version             = "1.0"

      hash                = "e88610db05636a1476435ec1f39d3651b080c8a6b8756452d421d7a822a2e115"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Clover Field ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "03:98:0d:54:38:8f:05:21:99:a4:89:39:d5:20:3c:0c"
      cert_thumbprint     = "1C2C084FB6E18A4033B63E619868CF81819BF46E"
      cert_valid_from     = "2023-12-14"
      cert_valid_to       = "2024-12-13"

      country             = "DK"
      state               = "Region of Southern Denmark"
      locality            = "Nyborg"
      email               = "???"
      rdn_serial_number   = "33584113"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "03:98:0d:54:38:8f:05:21:99:a4:89:39:d5:20:3c:0c"
      )
}
