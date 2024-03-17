using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models;

public class UserRegisterDto
{
    public string username { get; set; }
    public string password { get; set; }
    public string fname { get; set; }
    public string lname { get; set; }
    public string email { get; set; }
}