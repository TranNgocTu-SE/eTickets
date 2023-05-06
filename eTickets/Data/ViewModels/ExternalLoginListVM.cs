using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace eTickets.Data.ViewModels
{
    public class ExternalLoginListVM
    {
        public IList<AuthenticationScheme> ExternalLogins { get; set; }
        public string ReturnUrl { get; set; }
    }

    public class ExternalLoginConfirmVM
    {
        [Required]
        public string Email { get; set; }
    }
}
