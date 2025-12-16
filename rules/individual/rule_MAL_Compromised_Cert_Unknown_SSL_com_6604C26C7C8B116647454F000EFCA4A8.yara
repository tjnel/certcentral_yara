import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6604C26C7C8B116647454F000EFCA4A8 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-10"
      version             = "1.0"

      hash                = "9794c2f6949b96de153acc516d901140353ec9597d8822539a1fd1d629e12571"
      malware             = "Unknown"
      malware_type        = "Infostealer"
      malware_notes       = "The malware was disguised as a PDF. The file itself is an InnoSetup installer with a password protected payload."

      signer              = "DESKFUND BENEFIT NIDHI LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "66:04:c2:6c:7c:8b:11:66:47:45:4f:00:0e:fc:a4:a8"
      cert_thumbprint     = "CAAA615F6FFF277DF49504D4D42A291C19982C02"
      cert_valid_from     = "2025-10-10"
      cert_valid_to       = "2026-10-10"

      country             = "IN"
      state               = "Uttar Pradesh"
      locality            = "Raebareli"
      email               = "???"
      rdn_serial_number   = "UDYAM-UP-43-0159626"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "66:04:c2:6c:7c:8b:11:66:47:45:4f:00:0e:fc:a4:a8"
      )
}
