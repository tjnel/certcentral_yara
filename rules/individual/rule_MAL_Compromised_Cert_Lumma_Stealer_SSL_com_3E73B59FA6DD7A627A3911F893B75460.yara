import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_3E73B59FA6DD7A627A3911F893B75460 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-04"
      version             = "1.0"

      hash                = "2406de4418048f119679d91f3e168ed8a0bf3e77c706295bb69598b220c173d2"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "It Best Management Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3e:73:b5:9f:a6:dd:7a:62:7a:39:11:f8:93:b7:54:60"
      cert_thumbprint     = "89BE52E6CA45C95023D0000554438A7671E63B0D"
      cert_valid_from     = "2024-04-04"
      cert_valid_to       = "2025-04-04"

      country             = "GB"
      state               = "???"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "08158198"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3e:73:b5:9f:a6:dd:7a:62:7a:39:11:f8:93:b7:54:60"
      )
}
