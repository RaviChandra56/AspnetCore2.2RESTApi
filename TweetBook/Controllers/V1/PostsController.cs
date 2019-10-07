using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using TweetBook.Contracts.V1;
using TweetBook.Contracts.V1.Requests;
using TweetBook.Contracts.V1.Responses;
using TweetBook.Domain;

namespace TweetBook.Controllers.V1
{
    public class PostsController : Controller
    {
        private List<Post> _posts;
        public PostsController()
        {
            _posts = new List<Post>();
            for (int i = 0; i < 5; i++ )
            {
                _posts.Add(new Post { Id =Guid.NewGuid().ToString() });
            }
        }

        [HttpGet(ApiRoutes.Posts.GetAll)]
        public IActionResult GetAll()
        {
            return Ok(_posts);
        }

        [HttpPost(ApiRoutes.Posts.Create)]
        public IActionResult Create([FromBody]CreatePostRequest createPostRequest)
        {
            var post = new Post {Id = createPostRequest.Id};

            if (!string.IsNullOrEmpty(post.Id))
            {
                post.Id = Guid.NewGuid().ToString();
            }
            _posts.Add(post);

            var baseUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host.ToUriComponent()}";
            var locationUri = baseUrl + "/" + ApiRoutes.Posts.Get.Replace("{postId}", post.Id);

            var response = new PostResponse { Id = post.Id };
            return Created(locationUri, response);
        }
    }
}