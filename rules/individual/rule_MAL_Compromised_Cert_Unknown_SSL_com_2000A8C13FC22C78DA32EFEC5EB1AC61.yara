import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2000A8C13FC22C78DA32EFEC5EB1AC61 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-13"
      version             = "1.0"

      hash                = "849abdff0d8be4a64e0d966a104df8d44548edc8d4c618ea4edcfc6ff630d45c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ionik Software Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "20:00:a8:c1:3f:c2:2c:78:da:32:ef:ec:5e:b1:ac:61"
      cert_thumbprint     = "6822CB06EA9371C10F262694B60CD49038F0D05C"
      cert_valid_from     = "2024-08-13"
      cert_valid_to       = "2025-08-06"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "20:00:a8:c1:3f:c2:2c:78:da:32:ef:ec:5e:b1:ac:61"
      )
}
