import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_00B649A966410F62999C939384AF553919 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-05-27"
      version             = "1.0"

      hash                = "70eae6d411554b0587f9bc3e7e7cc753e81b8086310dc5fa8181c44632fe1ada"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "F.A.T. SARL"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19"
      cert_thumbprint     = "5968A4ED4AC1CBE7DD7F36B9A4E651CCDD47D07A"
      cert_valid_from     = "2020-05-27"
      cert_valid_to       = "2021-05-27"

      country             = "FR"
      state               = "Paris 18e Arrondissement"
      locality            = "Paris 18e Arrondissement"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19"
      )
}
