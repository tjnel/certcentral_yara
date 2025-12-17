import "pe"

rule MAL_Compromised_Cert_BaoLoader_Sectigo_313CA9C838CDDB21E4E354E6DBF0216A {
   meta:
      description         = "Detects BaoLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-28"
      version             = "1.0"

      hash                = "7c86ebc6bb775b6b35c4f70140f6e18908b7f3a15f9bffe33da96fee4601d74d"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Native Click Marketing LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "31:3c:a9:c8:38:cd:db:21:e4:e3:54:e6:db:f0:21:6a"
      cert_thumbprint     = "2435F8517B48DACB8B000DB25A176D12714BD628"
      cert_valid_from     = "2024-11-28"
      cert_valid_to       = "2027-11-28"

      country             = "US"
      state               = "Delaware"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "31:3c:a9:c8:38:cd:db:21:e4:e3:54:e6:db:f0:21:6a"
      )
}
