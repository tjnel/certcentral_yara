import "pe"

rule MAL_Compromised_Cert_Onyx_RMM_SSL_com_7301BD775D3E4DC6539B217A2C3CB137 {
   meta:
      description         = "Detects Onyx RMM with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-03"
      version             = "1.0"

      hash                = "1fd040c91b03f71d5a120f3c6b696da441d8424ba6f874991f5e7f1b014beb65"
      malware             = "Onyx RMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISSY'S CREDIBLE CLEANING LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "73:01:bd:77:5d:3e:4d:c6:53:9b:21:7a:2c:3c:b1:37"
      cert_thumbprint     = "CDE577D14506EA213ED20C15014336586F3B18A3"
      cert_valid_from     = "2025-09-03"
      cert_valid_to       = "2026-09-03"

      country             = "US"
      state               = "Florida"
      locality            = "Cape Coral"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "73:01:bd:77:5d:3e:4d:c6:53:9b:21:7a:2c:3c:b1:37"
      )
}
