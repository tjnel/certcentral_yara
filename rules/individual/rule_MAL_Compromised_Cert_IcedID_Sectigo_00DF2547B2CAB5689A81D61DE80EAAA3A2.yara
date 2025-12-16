import "pe"

rule MAL_Compromised_Cert_IcedID_Sectigo_00DF2547B2CAB5689A81D61DE80EAAA3A2 {
   meta:
      description         = "Detects IcedID with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-14"
      version             = "1.0"

      hash                = "943aa6d0267127142cd9d191c32b138559d67df2b9a352eacd4b86620336ac2e"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "FORWARD MUSIC AGENCY SRL"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2"
      cert_thumbprint     = "8E816DEB45E8298DAA2598459C9E9CC3B157B369"
      cert_valid_from     = "2022-07-14"
      cert_valid_to       = "2023-07-14"

      country             = "RO"
      state               = "București"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2"
      )
}
