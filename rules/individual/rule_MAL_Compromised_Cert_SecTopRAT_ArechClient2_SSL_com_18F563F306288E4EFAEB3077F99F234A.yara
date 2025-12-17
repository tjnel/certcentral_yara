import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_SSL_com_18F563F306288E4EFAEB3077F99F234A {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-07"
      version             = "1.0"

      hash                = "27b1281daa3529ce465df70b5436c5ea3413cd054f4b9ecabbfdf278f1a109b4"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Capsule Software"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "18:f5:63:f3:06:28:8e:4e:fa:eb:30:77:f9:9f:23:4a"
      cert_thumbprint     = "DBD7FA9C157B0440336D479CFEAD517CE2BB6655"
      cert_valid_from     = "2025-01-07"
      cert_valid_to       = "2026-01-07"

      country             = "FR"
      state               = "Occitania"
      locality            = "Montpellier"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "18:f5:63:f3:06:28:8e:4e:fa:eb:30:77:f9:9f:23:4a"
      )
}
