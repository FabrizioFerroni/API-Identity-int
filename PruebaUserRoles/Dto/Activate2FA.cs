namespace PruebaUserRoles.Dto
{
    public class Activate2FA
    {
        public bool IsActivated { get; set; }
        public string Email { get; set; }

        public Activate2FA()
        {
            IsActivated = false;
        }

    }
}
