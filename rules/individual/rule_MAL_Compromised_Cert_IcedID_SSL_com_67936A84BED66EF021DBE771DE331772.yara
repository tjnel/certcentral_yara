import "pe"

rule MAL_Compromised_Cert_IcedID_SSL_com_67936A84BED66EF021DBE771DE331772 {
   meta:
      description         = "Detects IcedID with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-01"
      version             = "1.0"

      hash                = "130360ea85121a0af3f7ea729b9026c911e5d543ba61ebdd637ebbe23df1c2c8"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "APEX SOFTWARE DESIGN, LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "67:93:6a:84:be:d6:6e:f0:21:db:e7:71:de:33:17:72"
      cert_thumbprint     = "A9F42777E0C9B35CC058C68B1788F2D74DEE6DED"
      cert_valid_from     = "2023-05-01"
      cert_valid_to       = "2024-04-30"

      country             = "US"
      state               = "Louisiana"
      locality            = "Baton Rouge"
      email               = "???"
      rdn_serial_number   = "43646041K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "67:93:6a:84:be:d6:6e:f0:21:db:e7:71:de:33:17:72"
      )
}
