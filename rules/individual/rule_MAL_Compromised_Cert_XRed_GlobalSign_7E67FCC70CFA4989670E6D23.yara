import "pe"

rule MAL_Compromised_Cert_XRed_GlobalSign_7E67FCC70CFA4989670E6D23 {
   meta:
      description         = "Detects XRed with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "b27c43cf62df0388d7be0f26191f2ed5c39e485a2fd877bc7c715b3c9a558afc"
      malware             = "XRed"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen UCL Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7e:67:fc:c7:0c:fa:49:89:67:0e:6d:23"
      cert_thumbprint     = "047CD4B8D05B99A1934E8E27C751C00C10338472"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2025-11-14"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7e:67:fc:c7:0c:fa:49:89:67:0e:6d:23"
      )
}
