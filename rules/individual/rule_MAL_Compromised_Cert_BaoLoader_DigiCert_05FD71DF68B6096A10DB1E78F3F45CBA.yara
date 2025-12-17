import "pe"

rule MAL_Compromised_Cert_BaoLoader_DigiCert_05FD71DF68B6096A10DB1E78F3F45CBA {
   meta:
      description         = "Detects BaoLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-19"
      version             = "1.0"

      hash                = "baa1d067ab1a30d8c25f3837332268b954784b1941bc1c9883f6f7ab7a548987"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Blaze Media Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:fd:71:df:68:b6:09:6a:10:db:1e:78:f3:f4:5c:ba"
      cert_thumbprint     = "4E84A36046C9C0359E728248C02514EB3CAA61A7"
      cert_valid_from     = "2022-09-19"
      cert_valid_to       = "2023-09-20"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704406"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:fd:71:df:68:b6:09:6a:10:db:1e:78:f3:f4:5c:ba"
      )
}
