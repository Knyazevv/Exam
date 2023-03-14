using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.ViewModels.User;
using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _18_E_LEARN.DataAccess.Validation.Categories
{
    public class EditCategoryValidation : AbstractValidator<Category>
    {
        public EditCategoryValidation()
        {
            RuleFor(r => r.Name).NotEmpty();
        }
    }
}
