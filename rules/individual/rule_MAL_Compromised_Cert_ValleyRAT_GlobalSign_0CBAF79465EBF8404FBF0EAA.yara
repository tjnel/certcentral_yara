import "pe"

rule MAL_Compromised_Cert_ValleyRAT_GlobalSign_0CBAF79465EBF8404FBF0EAA {
   meta:
      description         = "Detects ValleyRAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-20"
      version             = "1.0"

      hash                = "7ffd77507493be9e2370139ae1116a8175ca7358378e121d6cb2ccdc27fe6912"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xi'an Vanci Electronic Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:ba:f7:94:65:eb:f8:40:4f:bf:0e:aa"
      cert_thumbprint     = "F3CC4793FAD912A4E2B628DF42D51627231CA2C5"
      cert_valid_from     = "2025-05-20"
      cert_valid_to       = "2027-05-21"

      country             = "CN"
      state               = "Shaanxi"
      locality            = "Xi'an"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:ba:f7:94:65:eb:f8:40:4f:bf:0e:aa"
      )
}
