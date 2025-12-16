import "pe"

rule MAL_Compromised_Cert_WebCompanion_Adware_SSL_com_05582E18BF2CBA8BA45073BBAED945F8 {
   meta:
      description         = "Detects WebCompanion Adware with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-04"
      version             = "1.0"

      hash                = "b0455e876ebafb3da28d545c4b1bba3c945a0360dac165db22e74b89053edbb9"
      malware             = "WebCompanion Adware"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Eclipse Media Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "05:58:2e:18:bf:2c:ba:8b:a4:50:73:bb:ae:d9:45:f8"
      cert_thumbprint     = "3929E3C4FBC9A6E06D46CFAEEAB579CC7AEE39AB"
      cert_valid_from     = "2023-04-04"
      cert_valid_to       = "2026-04-03"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704432"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "05:58:2e:18:bf:2c:ba:8b:a4:50:73:bb:ae:d9:45:f8"
      )
}
