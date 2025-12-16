import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_SSL_com_4C46DCF5B0C4357F05806830DBA932FD {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-18"
      version             = "1.0"

      hash                = "fe40afb158e24c1896776fe3bdef33d2bb85ae67cf7b115f309d2535fc2a6afd"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "TRADE TRUST LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "4c:46:dc:f5:b0:c4:35:7f:05:80:68:30:db:a9:32:fd"
      cert_thumbprint     = "FEA61825376A364886B5236EFCB3EDD1B23E9441"
      cert_valid_from     = "2024-11-18"
      cert_valid_to       = "2025-11-18"

      country             = "UA"
      state               = "???"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "37058412"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "4c:46:dc:f5:b0:c4:35:7f:05:80:68:30:db:a9:32:fd"
      )
}
