import "pe"

rule MAL_Compromised_Cert_IcedID_Sectigo_00CA7D54577243934F665FD1D443855A3D {
   meta:
      description         = "Detects IcedID with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-12"
      version             = "1.0"

      hash                = "f56ea10521a52f78bedbf51c0bbdf9c894e473a73f1da8d388afc85b4c95f727"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "FABO SP Z O O"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ca:7d:54:57:72:43:93:4f:66:5f:d1:d4:43:85:5a:3d"
      cert_thumbprint     = "BB1B413CC8678C2FB2AF345A53DA186BACE5850F"
      cert_valid_from     = "2020-10-12"
      cert_valid_to       = "2021-10-12"

      country             = "PL"
      state               = "MAZOWIECKIE"
      locality            = "Radom"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ca:7d:54:57:72:43:93:4f:66:5f:d1:d4:43:85:5a:3d"
      )
}
