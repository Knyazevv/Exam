using _18_E_LEARN.DataAccess.Data.IRepository;
using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.Models.Courses;
using _18_E_LEARN.DataAccess.Data.ViewModels.Course;
using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _18_E_LEARN.BusinessLogic.Services
{
    public class CategoryService
    {
        private readonly IMapper _mapper;
        private readonly ICategoryRepository _categoryRepository;
        public CategoryService(IMapper mapper, ICategoryRepository categoryRepository)
        {
            _categoryRepository = categoryRepository;
            _mapper = mapper;
        }

        public async Task<ServiceResponse> GetAllAsync()
        {
            List<Category> categories = await _categoryRepository.GetAllAsync();
            return new ServiceResponse
            {
                Success = true,
                Message = "All categories loaded.",
                Payload = categories
            };
        }

        public async Task<ServiceResponse> GetByIdAsync(int Id)
        {
            var result = await _categoryRepository.GetByIdAsync(Id);
            if (result == null)
            {
                return new ServiceResponse
                {
                    Success = false,
                    Message = "Category not found."
                };
            }

            return new ServiceResponse
            {
                Success = true,
                Message = "Category loaded.",
                Payload = result
            };
        }
        public async Task<ServiceResponse> Create(AddCategoryVM model)
        {
            var category = await _categoryRepository.GetByNameAsync(model.Name);
            if (category != null)
            {
                return new ServiceResponse
                {
                    Success = false,
                    Message = "Category exists.",
                };
            }
            var mappedCategory = _mapper.Map<AddCategoryVM, Category>(model);
            await _categoryRepository.Create(mappedCategory);

            return new ServiceResponse
            {
                Success = true,
                Message = "Category created.",
            };

        }

        public async Task<ServiceResponse> Update(Category model)
        {
            var category = await _categoryRepository.GetByNameAsync(model.Name);
            if (category != null)
            {
                return new ServiceResponse
                {
                    Success = false,
                    Message = "Category exists.",
                };
            }
            _categoryRepository.Update(model);

            return new ServiceResponse
            {
                Success = true,
                Message = "Category updated.",
            };

        }

        public async Task<ServiceResponse> Delete(int id)
        {
            var category = await _categoryRepository.GetByIdAsync(id);
            if (category == null)
            {
                return new ServiceResponse
                {
                    Success = false,
                    Message = "Category not exists.",
                };
            }
            await _categoryRepository.Delete(category);

            return new ServiceResponse
            {
                Success = true,
                Message = "Category successfully deleted.",
            };
        }
    }
}
