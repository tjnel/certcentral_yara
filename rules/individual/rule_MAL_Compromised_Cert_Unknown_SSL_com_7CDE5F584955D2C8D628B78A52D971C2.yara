import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7CDE5F584955D2C8D628B78A52D971C2 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-20"
      version             = "1.0"

      hash                = "90edf602e2da6be9a5512adce1354d79674eb41d977050d2b8d15f0eab29f090"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhongguan Biotechnology (Hunchun) Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7c:de:5f:58:49:55:d2:c8:d6:28:b7:8a:52:d9:71:c2"
      cert_thumbprint     = "AB33C3E5C1EC5AEEE951E39014563AB937735B9A"
      cert_valid_from     = "2025-03-20"
      cert_valid_to       = "2026-03-16"

      country             = "CN"
      state               = "Jilin"
      locality            = "Yanbian Prefecture"
      email               = "???"
      rdn_serial_number   = "91222404MA1468WM01"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7c:de:5f:58:49:55:d2:c8:d6:28:b7:8a:52:d9:71:c2"
      )
}
