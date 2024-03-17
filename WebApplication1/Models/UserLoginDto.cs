namespace WebApplication1.Models;
using System.ComponentModel.DataAnnotations;

public class UserLoginDto
{
    [Required]
    [MinLength(8)]
    public string username { get; set; }
    [Required]
    [MinLength(6)]
    public string password { get; set; }
}