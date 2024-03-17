using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models;

public class UserRegisterDto
{
    [Required]
    public string username { get; set; }
    [Required]
    public string password { get; set; }
    public string fname { get; set; }
    public string lname { get; set; }
    [Required]
    public string email { get; set; }
}