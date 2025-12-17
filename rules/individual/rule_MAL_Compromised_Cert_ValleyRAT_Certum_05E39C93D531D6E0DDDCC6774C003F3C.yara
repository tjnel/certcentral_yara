import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_05E39C93D531D6E0DDDCC6774C003F3C {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-04"
      version             = "1.0"

      hash                = "46149a4e6bd7f01e816ff0e98d10e2248f6560b8dc075a2bd00a48d7095c51d5"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "湖南蒂角企业管理服务有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "05:e3:9c:93:d5:31:d6:e0:dd:dc:c6:77:4c:00:3f:3c"
      cert_thumbprint     = "A88E8CD81805E8E4768419711DA1575B76C1B2BC"
      cert_valid_from     = "2025-11-04"
      cert_valid_to       = "2026-11-04"

      country             = "CN"
      state               = "Hunan"
      locality            = "Changsha"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "05:e3:9c:93:d5:31:d6:e0:dd:dc:c6:77:4c:00:3f:3c"
      )
}
