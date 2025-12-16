import "pe"

rule MAL_Compromised_Cert_BaoLoader_DigiCert_0F493BE626DF58694E1875FA9155D40C {
   meta:
      description         = "Detects BaoLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-10"
      version             = "1.0"

      hash                = "35ab1c46e0341e6cda9ba1db61e8d8c0496df90ee758ed02d15f564a62b35da8"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Astral Media Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA"
      cert_serial         = "0f:49:3b:e6:26:df:58:69:4e:18:75:fa:91:55:d4:0c"
      cert_thumbprint     = "5514956084DC1DADD32218509CA6F184816FAB71"
      cert_valid_from     = "2021-05-10"
      cert_valid_to       = "2022-05-12"

      country             = "PA"
      state               = "Panama"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704413"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA" and
         sig.serial == "0f:49:3b:e6:26:df:58:69:4e:18:75:fa:91:55:d4:0c"
      )
}
