import { useContext, useEffect } from "react";
import { BlogContext } from "../pages/blog.page";
import { UserContext } from "../App";
import { Link } from "react-router-dom";
import { toast, Toaster } from "react-hot-toast";
import axios from "axios";

const BlogInteraction = () => {
	let {
		blog: {
			_id,
			title,
			blog_id,
			activity,
			activity: { total_likes, total_comments },
			author: {
				personal_info: { username: author_username },
			},
		},
		blog,
		setBlog,
		isLikedByUser,
		setIsLikedByUser,
		setCommentsWrapper,
	} = useContext(BlogContext);

	const {
		userAuth: { username, access_token },
	} = useContext(UserContext);

	useEffect(() => {
		if (access_token) {
			axios
				.post(
					import.meta.env.VITE_SERVER_DOMAIN + "/api/is-liked-by-user",
					{ _id },
					{
						headers: {
							Authorization: `${access_token}`,
						},
					},
				)
				.then(({ data: { result } }) => {
					setIsLikedByUser(Boolean(result));
				})
				.catch(err => console.log(err));
		}
	}, []);

	const handleLike = () => {
		if (access_token) {
			setIsLikedByUser(prevState => !prevState);

			!isLikedByUser ? total_likes++ : total_likes--;

			setBlog({ ...blog, activity: { ...activity, total_likes } });

			axios
				.post(
					import.meta.env.VITE_SERVER_DOMAIN + "/api/like-blog",
					{ _id, isLikedByUser },
					{
						headers: {
							Authorization: `${access_token}`,
						},
					},
				)
				.then(({ data }) => {
					console.log(data);
				})
				.catch(err => console.log(err));
		} else {
			toast.error("Please log in to like this blog");
		}
	};

	return (
		<>
			<Toaster />
			<hr className="border-grey my-2" />
			<div className="flex gap-6 justify-between">
				<div className="flex gap-3 items-center">
					<button
						className={
							"w-10 h-10 rounded-full flex items-center justify-center " +
							(isLikedByUser ? "bg-red/20 text-red" : "bg-grey/80")
						}
						onClick={handleLike}
					>
						<i className={"fi " + (isLikedByUser ? "fi-sr-heart" : "fi-rr-heart")}></i>
					</button>
					<p className="text-xl text-dark-grey">{total_likes}</p>
					<button
						className="w-10 h-10 rounded-full flex items-center justify-center bg-grey/80"
						onClick={() => setCommentsWrapper(prevValue => !prevValue)}
					>
						<i className="fi fi-rr-comment-dots"></i>
					</button>
					<p className="text-xl text-dark-grey">{total_comments}</p>
				</div>
				<div className="flex gap-6 items-center">
					{username === author_username ? (
						<Link to={`/editor/${blog_id}`} className="underline hover:text-purple">
							Edit
						</Link>
					) : null}

					<Link to={`https://twitter.com/intent/tweet?text=Read${title}&url=${location.href}`}>
						<i className="fi fi-brands-twitter text-xl hover:text-twitter"></i>
					</Link>
				</div>
			</div>
			<hr className="border-grey my-2" />
		</>
	);
};

export default BlogInteraction;
