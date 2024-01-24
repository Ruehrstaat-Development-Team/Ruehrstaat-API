package mailer

import "strings"

// TODO PUT RUEHRSTAAT LOGO INSTEAD OF MTN LOGO

var template = map[string]string{
	"de": `
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <title>MTN Mail Template</title>
</head>
<body style="margin: 0; padding: 0; width: 100%; text-align: center">
  <table width="700" border="0" cellspacing="0" cellpadding="0" align="center">
    <tr>
      <td colspan="3">
        <img src="https://cdn.mtnmedia.group/banner.png" alt="Banner" width="600">
      </td>
    </tr>
    <tr>
      <td width="25"></td>
      <td style="font-family: Helvetica, Arial, sans-serif; font-size: 17px; padding: 25px">
        Hi {{name}},<br/>
        {{content}}

        <br><br>
        Dein Ruehrstaat Team
      </td>
      <td width="25"></td>
    </tr>
    <tr>
      <td colspan="3" style="text-align: center; padding: 20px;">
        <img src="https://cdn.mtnmedia.group/logo.png" alt="MTN Logo" width="50">
      </td>
    </tr>
  </table>
</body>
</html>
`,
	"en": `
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <title>MTN Mail Template</title>
</head>
<body style="margin: 0; padding: 0; width: 100%; text-align: center">
  <table width="700" border="0" cellspacing="0" cellpadding="0" align="center">
    <tr>
      <td colspan="3">
        <img src="https://cdn.mtnmedia.group/banner.png" alt="Banner" width="600">
      </td>
    </tr>
    <tr>
      <td width="25"></td>
      <td style="font-family: Helvetica, Arial, sans-serif; font-size: 17px; padding: 25px">
        Hi {{name}},<br/>
        {{content}}

        <br><br>
        Your Ruehrstaat Team
      </td>
      <td width="25"></td>
    </tr>
    <tr>
      <td colspan="3" style="text-align: center; padding: 20px;">
        <img src="https://cdn.mtnmedia.group/logo.png" alt="MTN Logo" width="50">
      </td>
    </tr>
  </table>
</body>
</html>
  `,
}

func buildTemplate(name string, content string, locale string) string {
	s := strings.ReplaceAll(template[locale], "{{content}}", strings.ReplaceAll(content, "\n", "<br>"))
	s = strings.ReplaceAll(s, "{{name}}", name)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "  ", "")
	return s
}
