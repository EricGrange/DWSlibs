unit Security.reCaptcha;

interface

uses System.Net;

type

   TreCatchaResponse = record
      IsValid : Boolean;
      Error : String;
   end;

	ReCaptcha = class

      class function GetHtmlCode(publicKey : String; error : String = ''): String; static;
      class function CheckAnswer(privateKey, remoteIp, challenge, response : String) : TreCatchaResponse; static;
	
	end;

implementation

class function ReCaptcha.GetHtmlCode(publicKey: String; error : String = ''): String;
begin
   var p := publicKey + (if error<>'' then error+'&error='+error);
   Result:='<script type="text/javascript" src="http://www.google.com/recaptcha/api/challenge?k='
      + p + #'
      "></script><noscript>
      <iframe src="http://www.google.com/recaptcha/api/noscript?k='
      + p + #'
      " height="300" width="500" frameborder="0"></iframe><br>
      <textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
      <input type="hidden" name="recaptcha_response_field" value="manual_challenge">
      </noscript>';
end;

class function ReCaptcha.CheckAnswer(privateKey, remoteIp, challenge, response: String): TreCatchaResponse;
begin
   var data :=
        'privatekey=' + privateKey
      + '&remoteip=' + remoteIp
      + '&challenge=' + challenge
      + '&response=' + response;

   var check : String;
   if HttpQuery.PostData('http://www.google.com/recaptcha/api/verify', data,
                         'application/x-www-form-urlencoded', check) = 200 then begin
      Result.IsValid := check.StartsWith('true');
      Result.Error := check.After(#10);
   end else begin
      Result.Error := 'ServerError';
   end;
end;

