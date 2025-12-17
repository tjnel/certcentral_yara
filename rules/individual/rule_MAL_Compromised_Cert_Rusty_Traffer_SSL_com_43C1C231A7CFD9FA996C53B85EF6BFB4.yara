import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_SSL_com_43C1C231A7CFD9FA996C53B85EF6BFB4 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-05"
      version             = "1.0"

      hash                = "716a87bcb87a4180d00904072a2c6e8c0e495b66cad88d5002f57b93ac214235"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIGITAL OUTDOOR SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "43:c1:c2:31:a7:cf:d9:fa:99:6c:53:b8:5e:f6:bf:b4"
      cert_thumbprint     = "9F31E7BA8883A747D660519FCC6FF5202442783C"
      cert_valid_from     = "2025-05-05"
      cert_valid_to       = "2026-05-05"

      country             = "PL"
      state               = "Lesser Poland Voivodeship"
      locality            = "Nowy Targ"
      email               = "???"
      rdn_serial_number   = "0000268851"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "43:c1:c2:31:a7:cf:d9:fa:99:6c:53:b8:5e:f6:bf:b4"
      )
}
