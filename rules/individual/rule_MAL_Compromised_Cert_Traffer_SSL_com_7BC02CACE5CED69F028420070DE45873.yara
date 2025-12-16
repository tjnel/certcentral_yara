import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_7BC02CACE5CED69F028420070DE45873 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-13"
      version             = "1.0"

      hash                = "c91645a923a96e4f03687f51e6569e448a10fd8d5493e451cbe2d94eedb36578"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIG TECH SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7b:c0:2c:ac:e5:ce:d6:9f:02:84:20:07:0d:e4:58:73"
      cert_thumbprint     = "09FD02E91ED02CFD57C31248944F24AFDF11CEC0"
      cert_valid_from     = "2025-06-13"
      cert_valid_to       = "2026-06-13"

      country             = "PL"
      state               = "Silesian Voivodeship"
      locality            = "Ruda Śląska"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7b:c0:2c:ac:e5:ce:d6:9f:02:84:20:07:0d:e4:58:73"
      )
}
