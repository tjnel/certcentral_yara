import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Certum_30F927F04880D925FB28775A412E8C13 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-21"
      version             = "1.0"

      hash                = "b2ef6a86983e15d0f70e5941b79d03419d4c7bcd4b1c58223f6b8334ed800deb"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "Loads payloads from AWS S3 bucket. downloads 503 JPG from bucket as decoy: https://tria.ge/251129-r55s4szpem/behavioral1"

      signer              = "Shanghai Baiyang Information Technology Development Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "30:f9:27:f0:48:80:d9:25:fb:28:77:5a:41:2e:8c:13"
      cert_thumbprint     = "CC2172E282D7443E956F090A6795E33BF817A927"
      cert_valid_from     = "2025-11-21"
      cert_valid_to       = "2026-11-21"

      country             = "CN"
      state               = "上海市"
      locality            = "上海市"
      email               = "???"
      rdn_serial_number   = "91310000MADNJP1G00"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "30:f9:27:f0:48:80:d9:25:fb:28:77:5a:41:2e:8c:13"
      )
}
