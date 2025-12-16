import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_SSL_com_7B6CACE36104A90BFF22224F0AFDB52D {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-03"
      version             = "1.0"

      hash                = "6cb35e6d5e3dc675d2b2fac2e86012d3da4134b213169ef26481c4eb2f90845a"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Shanghai Cabo Paint Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7b:6c:ac:e3:61:04:a9:0b:ff:22:22:4f:0a:fd:b5:2d"
      cert_thumbprint     = "C7276BCA5CC66922B0C03076FCC62DF4D1E7983D"
      cert_valid_from     = "2024-06-03"
      cert_valid_to       = "2025-06-02"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310115607394704N"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7b:6c:ac:e3:61:04:a9:0b:ff:22:22:4f:0a:fd:b5:2d"
      )
}
