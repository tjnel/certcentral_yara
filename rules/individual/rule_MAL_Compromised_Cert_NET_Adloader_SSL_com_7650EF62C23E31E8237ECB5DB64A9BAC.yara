import "pe"

rule MAL_Compromised_Cert_NET_Adloader_SSL_com_7650EF62C23E31E8237ECB5DB64A9BAC {
   meta:
      description         = "Detects .NET Adloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-11"
      version             = "1.0"

      hash                = "7d86a15da892322e14c2d892afb4fd56772d098bd4d91578c6e6bb5366d4f9f4"
      malware             = ".NET Adloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Drake Media Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "76:50:ef:62:c2:3e:31:e8:23:7e:cb:5d:b6:4a:9b:ac"
      cert_thumbprint     = "8AF2C1B537D7ABF208B1F6957EEACA8A4158B05C"
      cert_valid_from     = "2023-03-11"
      cert_valid_to       = "2025-03-09"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704428"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "76:50:ef:62:c2:3e:31:e8:23:7e:cb:5d:b6:4a:9b:ac"
      )
}
