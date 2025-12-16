import "pe"

rule MAL_Compromised_Cert_FriendsCompany_Certum_49628D191450A16A85249183C7533D7F {
   meta:
      description         = "Detects FriendsCompany with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-07"
      version             = "1.0"

      hash                = "f83d5515a1f2cc04b486a30e87a00050f91a5d92c9a8db054113583c2d7c653f"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Chongqing Qirui Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "49:62:8d:19:14:50:a1:6a:85:24:91:83:c7:53:3d:7f"
      cert_thumbprint     = "31A8FE02E6873472379C292681CF698AF73BDE36"
      cert_valid_from     = "2025-03-07"
      cert_valid_to       = "2026-03-07"

      country             = "CN"
      state               = "Chongqing"
      locality            = "Chongqing"
      email               = "???"
      rdn_serial_number   = "91500107MA7FMGBN5F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "49:62:8d:19:14:50:a1:6a:85:24:91:83:c7:53:3d:7f"
      )
}
