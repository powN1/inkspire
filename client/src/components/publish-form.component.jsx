import { useContext } from "react";
import AnimationWrapper from "../common/page-animation";
import { toast, Toaster } from "react-hot-toast";
import { EditorContext } from "../pages/editor.pages";
import Tag from "./tags.component";
import { UserContext } from "../App";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";

const PublishForm = () => {
	const characterLimit = 200;
	const tagLimit = 10;

	const { blog_id } = useParams();

	const {
		blog,
		blog: { banner, title, tags, des, content },
		setEditorState,
		setBlog,
	} = useContext(EditorContext);

	let {
		userAuth: { access_token },
	} = useContext(UserContext);

	let navigate = useNavigate();

	const handleCloseEvent = () => {
		setEditorState("editor");
	};

	const handleBlogTitleChange = e => {
		const input = e.target;
		setBlog({ ...blog, title: input.value });
	};

	const handleBlogDescriptionChange = e => {
		const input = e.target;
		setBlog({ ...blog, des: input.value });
	};
	const handleDescriptionKeyDown = e => {
		if (e.keyCode === 13) {
			e.preventDefault();
		}
	};
	const handleTopicKeyDown = e => {
		if (e.keyCode === 13 || e.keyCode === 188) {
			e.preventDefault();

			const tag = e.target.value;

			if (tags.length < tagLimit) {
				if (!tags.includes(tag) && tag.length) {
					setBlog({ ...blog, tags: [...tags, tag] });
				}
			} else {
				toast.error(`You can add max ${tagLimit} tags`);
			}
			e.target.value = "";
		}
	};
	const handlePublishBlog = e => {
		if (e.target.className.includes("disable")) {
			return;
		}
		// validation
		if (!title.length) {
			return toast.error("Write blog title before publishing");
		}
		if (!des.length || des.length > characterLimit) {
			return toast.error(`Write blog description under ${characterLimit} before publishing`);
		}
		if (!tags.length) {
			return toast.error("Enter blog tags before publishing");
		}

		let loadingToast = toast.loading("Publishing...");

		e.target.classList.add("disable");

		let blogObj = {
			title,
			banner,
			des,
			content,
			tags,
			draft: false,
		};
		axios
			.post(
				import.meta.env.VITE_SERVER_DOMAIN + "/api/create-blog",
				{ ...blogObj, id: blog_id },
				{
					headers: {
						Authorization: `${access_token}`,
					},
				},
			)
			.then(() => {
				e.target.classList.remove("disable");

				toast.dismiss(loadingToast);
				toast.success("Published");

				setTimeout(() => {
					navigate("/dashboard/blogs");
				}, 500);
			})
			.catch(({ response }) => {
				e.target.classList.remove("disable");
				toast.dismiss(loadingToast);
				return toast.error(response.data.error);
			});
	};

	return (
		<AnimationWrapper>
			<section className="w-screen min-h-screen grid items-center lg:grid-cols-2 py-16 lg:gap-4">
				<Toaster />
				<button className="w-12 h-12 absolute right-[5vw] z-10 top-[5%] lg:top-[10%]" onClick={handleCloseEvent}>
					<i className="fi fi-br-cross"></i>
				</button>

				<div className="max-w-[550px] center">
					<p className="text-dark-grey mb-1">Preview</p>
					<div className="w-full aspect-video rounded-lg overflow-hidden bg-grey mt-4">
						<img src={banner} alt="banner" />
					</div>
					<h1 className="text-4xl font-medium mt-2 leading-tight line-clamp-2">{title}</h1>
					<p className="font-gelasio line-clamp-2 text-xl leading-7 mt-4">{des}</p>
				</div>
				<div className="border-grey lg:border-1 lg:pl-8">
					<p className="text-dark-grey mb-2 mt-9">Blog title</p>
					<input type="text" placeholder="Blog Title" defaultValue={title} className="input-box pl-4" onChange={handleBlogTitleChange} />

					<p className="text-dark-grey mb-2 mt-9">Short description about your blog</p>
					<textarea
						max-length={characterLimit}
						defaultValue={des}
						className="h-40 resize-none leading-7 input-box pl-4"
						onChange={handleBlogDescriptionChange}
						onKeyDown={handleDescriptionKeyDown}
					></textarea>
					<p className="mt-1 text-dark-grey text-sm text-right">{characterLimit - des.length} characters left</p>

					<p className="text-dark-grey mb-2 mt-9">Topics - (Helps in searching and ranking your blog post)</p>
					<div className="relative input-box pl-2 py-2 pb-4">
						<input
							type="text"
							placeholder="Topic"
							className="sticky input-box bg-white top-0 left-0 pl-4 mb-3 focus:bg-white"
							onKeyDown={handleTopicKeyDown}
						/>

						{tags.map((tag, i) => {
							return <Tag tag={tag} key={i} tagIndex={i} />;
						})}
					</div>
					<p className="mt-1 mb-4 text-dark-grey text-right text-sm">{tagLimit - tags.length} tags left</p>
					<button className="btn-dark px-8" onClick={handlePublishBlog}>
						Publish
					</button>
				</div>
			</section>
		</AnimationWrapper>
	);
};

export default PublishForm;
