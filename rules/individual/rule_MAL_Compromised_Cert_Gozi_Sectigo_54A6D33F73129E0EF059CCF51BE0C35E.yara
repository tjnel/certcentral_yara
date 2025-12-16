import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_54A6D33F73129E0EF059CCF51BE0C35E {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-13"
      version             = "1.0"

      hash                = "5bd267095b25bea0d5a95b4d6c22b871056ca7b8dc137351850d6a577ba62b80"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STAFFORD MEAT COMPANY, INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e"
      cert_thumbprint     = "8ADA307AB3A8983857D122C4CB48BF3B77B49C63"
      cert_valid_from     = "2020-11-13"
      cert_valid_to       = "2021-11-13"

      country             = "US"
      state               = "California"
      locality            = "Rio Linda"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e"
      )
}
