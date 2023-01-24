using Newtonsoft.Json.Linq;

namespace PruebaUserRoles.Dto
{
    public class LoginResponse
    {

        public int Status { get; set; }
        public string Message{ get; set; }

        public object Data { get; set; }

        public string Token { get; set; }

        public DateTime Expiration { get; set; }

        public LoginResponse() { }

    }
}
