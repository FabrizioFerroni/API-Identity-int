namespace PruebaUserRoles.Dto
{
    public class Response
    {
        public int? Status { get; set; }
        public string? Message { get; set; }
        public object? Data { get; set; }

        public Response()
        {
            this.Status = 404;
        }
    }
}
