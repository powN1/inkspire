import bcrypt from "bcrypt";
import cors from "cors";
import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { nanoid } from "nanoid";
import path from "path";
// firebase
import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";
import serviceAccountKey from "./react-blog-website-71d78-firebase-adminsdk-no9f5-1fed842c56.json" with { type: "json" };
//aws
import aws from "aws-sdk";

import Blog from "./Schema/Blog.js";
import Comment from "./Schema/Comment.js";
import Notification from "./Schema/Notification.js";
import User from "./Schema/User.js";

const server = express();

// Regex for identifying whether the email and password are correctly formatted
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

// Establish database connection
const PORT = process.env.PORT || 3004;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

mongoose.connect(process.env.DB_LOCATION, { autoIndex: true });

// setting up s3 bucket (aws)
const s3 = new aws.S3({
  region: "eu-central-1",
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const generateUploadUrl = async () => {
  const date = new Date();
  const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

  return await s3.getSignedUrlPromise("putObject", {
    Bucket: "reactjs-blogging-website1",
    Key: imageName,
    Expires: 1000,
    ContentType: "image/jpeg",
  });
};

// Middleware so the server can process json
server.use(express.json());
// Accept requests from different ports than backend port (3000)

if (process.env.NODE_ENV === "production") {
  // Accept requests only from patrykkurpiel.com when in production
  server.use(
    cors({
      // origin: "http://patrykkurpiel.com", // Your frontend URL
      origin: "*",
      methods: "GET,POST,PUT,DELETE", // Allowed HTTP methods
      allowedHeaders: "Content-Type,Authorization", // Allowed headers
    })
  );

  // Correct path to React build inside Docker

  const clientBuildPath = path.join(__dirname, "client/dist");
  console.log("client build path is ", clientBuildPath);
  server.use("/inkspire", express.static(clientBuildPath));

  // server.get("/inkspire/*", (req, res) => {
  //   res.sendFile(path.join(clientBuildPath, "index.html"));
  //   console.log("index.html path is ", path.join(clientBuildPath, "index.html"));
  // });
} else {
  // Accept requests from different ports than backend port (3000) for development
  server.use(cors());
  server.get("/", (req, res) => res.send("Please set to production"));
}

const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let usernameExists = await User.exists({
    "personal_info.username": username,
  }).then((res) => res);

  usernameExists ? (username += nanoid().substring(0, 5)) : "";

  return username;
};

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  // const token = authHeader && authHeader.split(" ")[1];
  const token = authHeader;

  if (token === null) {
    return res.status(401).json({ error: "No access token" });
  }
  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is invalid" });
    }

    req.user = user.id;
    req.admin = user.admin;
    next();
  });
};

const formatDataToSend = (user) => {
  const access_token = jwt.sign({ id: user._id, admin: user.admin }, process.env.SECRET_ACCESS_KEY);
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
    isAdmin: user.admin,
  };
};

// Handle "/signup" post request
server.post("/inkspire/api/signup", (req, res) => {
  const { fullname, email, password } = req.body;

  if (fullname.length < 3) {
    return res.status(403).json({ error: "Fullname must be at least 3 letters long" });
  }
  if (!email.length) {
    return res.status(403).json({ error: "Enter email" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email is invalid" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error: "Password should be 6-20 characters long with a numeric, 1 lowercase and 1 uppercase letters",
    });
  }

  // Use bcrypt to hash the password
  bcrypt.hash(password, 10, async (_err, hashed_password) => {
    const username = await generateUsername(email);

    const user = new User({
      personal_info: {
        fullname,
        email,
        password: hashed_password,
        username,
      },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDataToSend(u));
      })
      .catch((err) => {
        if (err.code === 11000) {
          return res.status(500).json({ error: "Email already exists" });
        }
        return res.status(500).json({ error: err.message });
      });
  });
});

server.post("/inkspire/api/signin", (req, res) => {
  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(403).json({
              error: "Error occured while logging in. Please try again.",
            });
          }

          if (!result) {
            return res.status(403).json({ error: "Incorrect password" });
          } else {
            return res.status(200).json(formatDataToSend(user));
          }
        });
      } else {
        return res.status(403).json({
          error: "Account was created using google. Try logging in with google.",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/google-auth", async (req, res) => {
  let { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;

      picture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email })
        .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth")
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });

      if (user) {
        //login
        if (!user.google_auth) {
          return res.status(403).json({
            error: "This email was signed up without google. Please log in with password to access the account.",
          });
        }
      } else {
        //signup
        let username = await generateUsername(email);

        user = new User({
          personal_info: { fullname: name, email, username },
          google_auth: true,
        });

        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json({ error: err.message });
          });
      }

      return res.status(200).json(formatDataToSend(user));
    })
    .catch((_err) => {
      return res.status(500).json({
        error: "Failed to authenticate with google. Try other account.",
      });
    });
});

server.post("/inkspire/api/create-blog", verifyJWT, (req, res) => {
  const authorId = req.user;

  let { title, des, banner, tags, content, draft, id } = req.body;

  // validation
  if (!title.length) {
    return res.status(403).json({ error: "You must provide a title" });
  }

  if (!draft) {
    if (!des.length || des.length > 200) {
      return res.status(403).json({
        error: "You must provide blog description under 200 characters",
      });
    }

    if (!banner.length) {
      return res.status(403).json({ error: "You must provide blog banner in order to publish it" });
    }

    if (!content.blocks.length) {
      return res.status(403).json({ error: "There must be some blog content to publish it" });
    }

    if (!tags.length || tags.length > 10) {
      return res.status(403).json({
        error: "You must provide max 10 blog tags in order to publish it",
      });
    }
  }

  tags = tags.map((tag) => tag.toLowerCase());

  let blog_id =
    id ||
    title
      .replace(/[^a-zA-Z0-9]/g, " ")
      .replace(/\s+/g, "-")
      .trim() + nanoid();

  if (id) {
    Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
      .then(() => {
        return res.status(200).json({ id: blog_id });
      })
      .catch((err) => {
        return res.status(500).json({ error: err.message });
      });
  } else {
    let blog = new Blog({
      title,
      des,
      banner,
      content,
      tags,
      author: authorId,
      blog_id,
      draft: Boolean(draft),
    });

    blog
      .save()
      .then((blog) => {
        let incrementVal = draft ? 0 : 1;

        User.findOneAndUpdate(
          { _id: authorId },
          {
            $inc: { "account_info.total_posts": incrementVal },
            $push: { blogs: blog._id },
          }
        )
          .then((_user) => {
            return res.status(200).json({ id: blog.blog_id });
          })
          .catch((_err) => {
            return res.status(500).json({ error: "Failed to update total posts number" });
          });
      })
      .catch((err) => {
        return res.status(500).json({ error: err.message });
      });
  }
});

server.post("/inkspire/api/like-blog", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { _id, isLikedByUser } = req.body;

  const incrementVal = !isLikedByUser ? 1 : -1;

  Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
    .then((blog) => {
      if (!isLikedByUser) {
        const like = new Notification({
          type: "like",
          blog: _id,
          notification_for: blog.author,
          user: user_id,
        });

        like
          .save()
          .then((_notification) => {
            return res.status(200).json({ liked_by_user: true });
          })
          .catch((err) => res.status(500).json({ error: err.message }));
      } else {
        Notification.findOneAndDelete({
          user: user_id,
          blog: _id,
          type: "like",
        })
          .then((_data) => {
            return res.status(200).json({ liked_by_user: false });
          })
          .catch((err) => res.status(500).json({ error: err.message }));
      }
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

server.post("/inkspire/api/get-blog", (req, res) => {
  const { blog_id, draft, mode } = req.body;

  let incrementVal = mode !== "edit" ? 1 : 0;

  Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } })
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then((blog) => {
      User.findOneAndUpdate(
        { "personal_info.username": blog.author.personal_info.username },
        {
          $inc: { "account_info.total_reads": incrementVal },
        }
      ).catch((err) => res.status(500).json({ error: err.message }));

      if (blog.draft && !draft) {
        return res.status(500).json({ error: "You can't access draft blog" });
      }

      return res.status(200).json({ blog });
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

server.post("/inkspire/api/search-blogs", (req, res) => {
  const { author, tag, page, query, limit, ignore_blog } = req.body;

  let findQuery;

  if (tag) {
    findQuery = { tags: tag, draft: false, blog_id: { $ne: ignore_blog } };
  } else if (query) {
    findQuery = { title: new RegExp(query, "i"), draft: false };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  const maxLimit = limit ? limit : 2;

  Blog.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.fullname personal_info.username -_id")
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/latest-blogs", (req, res) => {
  const { page } = req.body;

  const maxLimit = 5;

  Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.fullname personal_info.username -_id")
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/all-latest-blogs-count", (_req, res) => {
  Blog.countDocuments({ draft: false })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/search-blogs-count", (req, res) => {
  const { author, tag, query } = req.body;

  let findQuery;

  if (tag) {
    findQuery = { tags: tag, draft: false };
  } else if (query) {
    findQuery = { title: new RegExp(query, "i"), draft: false };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  Blog.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/search-users", (req, res) => {
  let { query } = req.body;

  User.find({ "personal_info.username": new RegExp(query, "i") })
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/get-profile", (req, res) => {
  const { username } = req.body;

  User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then((user) => {
      return res.status(200).json(user);
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// upload img url route
server.get("/inkspire/api/get-upload-url", (_req, res) => {
  generateUploadUrl()
    .then((url) => res.status(200).json({ uploadUrl: url }))
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.get("/inkspire/api/trending-blogs", (_req, res) => {
  Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.fullname personal_info.username -_id")
    .sort({
      "activity.total_reads": -1,
      "activity.total_likes": -1,
      publishedAt: -1,
    })
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/is-liked-by-user", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { _id } = req.body;

  Notification.exists({ user: user_id, type: "like", blog: _id })
    .then((result) => {
      return res.status(200).json({ result });
    })
    .catch((err) => res.status(500).json({ err: err.message }));
});

server.post("/inkspire/api/add-comment", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { _id, comment, blog_author, replying_to, notification_id } = req.body;

  if (!comment.length) {
    res.status(403).json({ error: "Write something to leave a comment" });
  }

  const commentObj = {
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id,
  };

  if (replying_to) {
    commentObj.parent = replying_to;
    commentObj.isReply = true;
  }

  new Comment(commentObj).save().then(async (commentFile) => {
    const { comment, commentedAt, children } = commentFile;

    Blog.findOneAndUpdate(
      { _id },
      {
        $push: { comments: commentFile._id },
        $inc: {
          "activity.total_comments": 1,
          "activity.total_parent_comments": replying_to ? 0 : 1,
        },
      }
    )
      .then((_blog) => {})
      .catch((err) => res.status(500).json({ error: err.message }));

    const notificationObj = {
      type: replying_to ? "reply" : "comment",
      blog: _id,
      notification_for: blog_author,
      user: user_id,
      comment: commentFile._id,
    };

    if (replying_to) {
      notificationObj.replied_on_comment = replying_to;

      await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
        .then((replyingToCommentDoc) => {
          notificationObj.notification_for = replyingToCommentDoc.commented_by;
        })
        .catch((err) => res.status(500).json({ error: err.message }));

      if (notification_id) {
        Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id }).then((notification) => {});
      }
    }

    new Notification(notificationObj)
      .save()
      .then((_notification) => {})
      .catch();

    return res.status(200).json({ comment, commentedAt, _id: commentFile._id, user_id, children });
  });
});

server.post("/inkspire/api/get-blog-comments", (req, res) => {
  const { blog_id, skip } = req.body;

  const maxLimit = 5;

  Comment.find({ blog_id, isReply: false })
    .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({ commentedAt: -1 })
    .then((comment) => {
      return res.status(200).json(comment);
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

server.post("/inkspire/api/get-replies", (req, res) => {
  const { _id, skip } = req.body;

  const maxLimit = 5;

  Comment.findOne({ _id })
    .populate({
      path: "children",
      options: {
        limit: maxLimit,
        skip: skip,
        sort: { commentedAt: -1 },
      },
      populate: {
        path: "commented_by",
        select: "personal_info.profile_img personal_info.fullname personal_info.username",
      },
      select: "-blog_id -updatedAt",
    })
    .select("children")
    .then((doc) => {
      return res.status(200).json({ replies: doc.children });
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

const deleteComments = (_id) => {
  console.log(`comment id is ${_id}`);

  Comment.findOneAndDelete({ _id })
    .then((comment) => {
      if (comment.parent) {
        Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
          .then((data) => console.log("comment deleted"))
          .catch((err) => console.log(err));
      }

      Notification.findOneAndDelete({ comment: _id })
        .then((notification) => console.log("comment notification deleted"))
        .catch((err) => console.log(err));

      Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } })
        .then((notification) => console.log("reply deleted"))
        .catch((err) => console.log(err));

      Blog.findOneAndUpdate(
        { _id: comment.blog_id },
        {
          $pull: { comments: _id },
          $inc: {
            "activity.total_comments": -1,
            "activity.total_parent_comments": comment.parent ? 0 : -1,
          },
        }
      )
        .then((blog) => {
          if (comment.children.length) {
            console.log(`Comment id: ${comment._id}, children arr: ${comment.children}, is reply?: ${comment.isReply}`);
            comment.children.map((replies) => {
              deleteComments(replies);
            });
          }
        })
        .catch((err) => console.log(err));
    })
    .catch((err) => console.log(err));
};

server.post("/inkspire/api/delete-comment", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { _id } = req.body;

  Comment.findOne({ _id }).then((comment) => {
    if (user_id == comment.commented_by || user_id == comment.blog_author) {
      deleteComments(_id);

      return res.status(200).json({ status: "Comment deleted" });
    } else {
      return res.status(403).json({ error: "You cannot delete this comment" });
    }
  });
});

server.post("/inkspire/api/change-password", verifyJWT, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  console.log(currentPassword, newPassword, req.user);

  if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
    return res.status(403).json({
      error: "Password should be 6-20 characters long with a numeric, 1 lowercase and 1 uppercase letters",
    });
  }

  User.findOneAndUpdate({ _id: req.user })
    .then((user) => {
      if (user.google_auth) {
        return res.status(403).json({
          error: "You can't change account's password because you logged in through google",
        });
      } else {
      }

      bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
        if (err) {
          return res.status(500).json({
            error: "Error occured while changing the password. Please try again later",
          });
        }

        if (!result) {
          return res.status(403).json({ error: "Incorrect current password" });
        }

        bcrypt.hash(newPassword, 10, (_err, hashedPassword) => {
          User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashedPassword })
            .then((_u) => {
              return res.status(200).json({ status: "Password changed" });
            })
            .catch((_err) => {
              return res.status(500).json({
                error: "Some error occured while saving new password. Please try again later",
              });
            });
        });
      });
    })
    .catch((_err) => {
      // console.log(err);
      return res.status(500).json({ error: "User not found" });
    });
});

server.post("/inkspire/api/update-profile-img", verifyJWT, (req, res) => {
  const { url } = req.body;

  User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
    .then(() => {
      return res.status(200).json({ profile_img: url });
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

server.post("/inkspire/api/update-profile", verifyJWT, (req, res) => {
  const { username, bio, social_links } = req.body;

  const bioLimit = 150;

  if (username.length < 3) {
    return res.status(403).json({ error: "Username should be at least 3 characters long" });
  }

  if (bio.length > bioLimit) {
    return res.status(403).json({
      error: `Bio should be shorter than ${bioLimit} characters long`,
    });
  }

  const socialLinksArray = Object.keys(social_links);
  try {
    for (let i = 0; i < socialLinksArray.length; i++) {
      if (social_links[socialLinksArray[i]].length) {
        const hostname = new URL(social_links[socialLinksArray[i]]).hostname;

        if (!hostname.includes(`${socialLinksArray[i]}.com`) && socialLinksArray[i] !== "website") {
          return res.status(403).json({
            error: `${socialLinksArray[i]} link is invalid. You must enter a full link`,
          });
        }
      }
    }

    const updatedObj = {
      "personal_info.username": username,
      "personal_info.bio": bio,
      social_links,
    };

    User.findOneAndUpdate({ _id: req.user }, updatedObj, {
      runValidators: true,
    })
      .then(() => {
        return res.status(200).json({ username });
      })
      .catch((err) => {
        if (err.code === 11000) {
          return res.status(409).json({ error: "Username is already taken" });
        }
        return res.status(500).json({ error: err.message });
      });
  } catch (err) {
    // console.log(err);
    return res.status(500).json({
      error: "You must provide social links with http(s) included" + err,
    });
  }
});

server.get("/inkspire/api/new-notification", verifyJWT, (req, res) => {
  const user_id = req.user;

  Notification.exists({
    notification_for: user_id,
    seen: false,
    user: { $ne: user_id },
  })
    .then((result) => {
      if (result) {
        return res.status(200).json({ new_notification_available: true });
      } else {
        return res.status(200).json({ new_notification_available: false });
      }
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/notifications", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { page, filter, deletedDocCount } = req.body;

  const maxLimit = 10;

  const findQuery = { notification_for: user_id, user: { $ne: user_id } };

  let skipDocs = (page - 1) * maxLimit;

  if (filter !== "all") {
    findQuery.type = filter;
  }

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
    .populate("comment", "comment")
    .populate("replied_on_comment", "comment")
    .populate("reply", "comment")
    .sort({ createdAt: -1 })
    .select("createdAt type seen reply")
    .then((notifications) => {
      Notification.updateMany(findQuery, { seen: true })
        .skip(skipDocs)
        .limit(maxLimit)
        .then(() => console.log("notification seen"))
        .catch((err) => console.log(err));
      return res.status(200).json({ notifications });
    })
    .catch((err) => {
      console.log(err.message);
      res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/all-notifications-count", verifyJWT, (req, res) => {
  const user_id = req.user;
  const { filter } = req.body;

  const findQuery = { notification_for: user_id, user: { $ne: user_id } };

  if (filter !== "all") {
    findQuery.type = filter;
  }

  Notification.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

server.post("/inkspire/api/user-written-blogs", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { page, draft, query, deletedDocCount } = req.body;

  const maxLimit = 5;
  let skipDocs = (page - 1) * maxLimit;

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  Blog.find({ author: user_id, draft, title: new RegExp(query, "i") })
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select("title banner publishedAt blog_id activity des draft -_id")
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ err: err.message });
    });
});

server.post("/inkspire/api/user-written-blogs-count", verifyJWT, (req, res) => {
  const user_id = req.user;

  const { draft, query } = req.body;

  Blog.countDocuments({
    author: user_id,
    draft,
    title: new RegExp(query, "i"),
  })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ err: err.message });
    });
});

server.post("/inkspire/api/delete-blog", verifyJWT, (req, res) => {
  const user_id = req.user;
  const { blog_id } = req.body;

  Blog.findOneAndDelete({ blog_id })
    .then((blog) => {
      Notification.deleteMany({ blog: blog._id }).then((data) => console.log("notifications deleted"));

      Comment.deleteMany({ blog_id: blog._id }).then((data) => console.log("comments deleted"));

      User.findOneAndUpdate(
        { _id: user_id },
        {
          $pull: { blog: blog._id },
          $inc: { "account_info.total_posts": blog.draft ? 0 : -1 },
        }
      ).then((user) => console.log("user info updated"));

      return res.status(200).json({ status: "done" });
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

server.listen(PORT, () => {
  console.log(`listening on port: ${PORT}`);
});
